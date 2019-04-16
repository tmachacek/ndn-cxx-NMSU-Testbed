/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2018 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 * @author Travis Machacek <tmachace@cs.nmsu.edu>
 */

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <unordered_map>
#include <iostream>
#include "AES_Code.hpp"
#include <openssl/rand.h>
#include <memory>
#include <bitset>
#include <unistd.h>
#include <string>
typedef std::pair<int, std::string> ID_Name;

std::unordered_map<int, byte[AES_STANDARD] > consumerMapping;
std::unordered_map<int, std::string> ivMapping;
std::unordered_map<int, int> consumerUpdate;
std::unordered_map<uint32_t, int> uniquePseudonym;
std::multimap<std::string, ID_Name> nameMapping;
std::multimap<std::string, ID_Name>::iterator NMit;


// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces can be used to prevent/limit name conflicts
namespace examples {

class Producer : noncopyable
{
public:
  void
  run()
  {
    m_face.setInterestFilter("/proxy",
                             bind(&Producer::onInterest, this, _1, _2),
                             RegisterPrefixSuccessCallback(),
                             bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

private:
  void
  onInterest(const InterestFilter& filter, const Interest& interest)
  {
    // Got a registration ineterest
    if(interest.getName().toUri().find("registration") != std::string::npos){
      registerConsumer(interest);
      return;
    }
    // Got a content interest
    else{
      relayInterest(interest);
    }

  }

  // Decrypt interest name to send to producer
  void relayInterest(const Interest& interest){
    Name interestName = interest.getName().getSubName(2,1);
    int consID = stoi(interest.getName().getSubName(1,1).toUri().substr(1));
    std::cout << "Received Interest: " << interest.getName().toUri() <<std::endl;

    // create key and iv and initalize them
    byte key[AES_STANDARD];
    memset(key, 0x00, AES_STANDARD);
    byte iv[AES_STANDARD];
    memset(iv, 0x00, AES_STANDARD);
   
    // get key from consumerMapping
    for(int i = 0; i < AES_STANDARD; i++){
      key[i] = consumerMapping.find(consID)->second[i];
    }
    // Retrieve IV from interest
    Block ivFromBlock = interest.getApplicationParameters();
    unsigned char *IV = const_cast<unsigned char*>(ivFromBlock.value());
    for(int j = 0; j < AES_STANDARD; j++){
      iv[j] = (byte)IV[j];
    }

    // Get string to decrypt
    Block comp = interest.getName()[-1].wireEncode();
    std::string ciphertext((char*)comp.value(), comp.value_size());
    std::string dec;
    
    // Decrypt interest and store it in string
    std::string decryptedString = AES_Dec(key,iv,ciphertext,dec);

    // Insert decrypted string, consumerID, and interest name for relayData() to use later
    nameMapping.insert(std::make_pair(decryptedString,std::make_pair(consID, interest.getName().toUri())));


    //We do minus 1 because of one byte of hex null at the end of decryption
    Name decryptedName(decryptedString.substr(0,decryptedString.size()-1));

    // Create interest for producer
    Interest interest2(decryptedName);
    interest2.setInterestLifetime(2_s);
    interest2.setMustBeFresh(true);
    std::cout << "Sending interest >> " << interest2.getName().toUri() <<std::endl; 

    m_face.expressInterest(interest2,
                           bind(&Producer::onData, this,  _1, _2),
                           bind(&Producer::onNack, this, _1, _2),
                           bind(&Producer::onTimeout, this, _1)); 

  }//end


  //Called only once per consumer
  void registerConsumer(const Interest& interest){
    std::cout << "Registering Consumer\n";
    std::string consID = interest.getName().getSubName(2,1).toUri().substr(1);
    int consumerID = stoi(consID);
    byte key[AES_STANDARD];
    memset(key, 0x00, AES_STANDARD);
    RAND_bytes(key,sizeof(key)-1);
    
    // Save key for consumer to unordered map
    for(int i = 0; i < AES_STANDARD; i++){
      consumerMapping[consumerID][i] = key[i];
    }
    
    std::cout << "<< I: " << interest << std::endl;

    // Create new name, based on Interest's name
    Name dataName(interest.getName());
    dataName
      .append("testApp") // add "testApp" component to Interest name
      .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)


    // Create Data packet
    shared_ptr<Data> data = make_shared<Data>();
    data->setName(dataName);
    data->setFreshnessPeriod(10_s); // 10 seconds
    data->setContent(reinterpret_cast<const uint8_t*>(key), sizeof(key));

    // Sign Data packet with default identity
    m_keyChain.sign(*data);
    // m_keyChain.sign(data, <identityName>);
    // m_keyChain.sign(data, <certificate>);

    // Return Data packet to the requester
    //std::cout << ">> D: " << *data << std::endl;
    m_face.put(*data);

  }
  
  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix \""
              << prefix << "\" in local hub's daemon (" << reason << ")"
              << std::endl;
    m_face.shutdown();
  }

  void onData(const Interest& interest, const Data& data){
     std::cout << "\nReceived data from Producer: " << data << std::endl;
     std::string str = data.getName().toUri();
     bool done;
     NMit = nameMapping.equal_range(str.substr(0, str.size()-3)).first;
     do {
       if(str.compare((*NMit).first))
          relayData(data, NMit);
       if(NMit == nameMapping.equal_range(str).second)
         done = true;
         nameMapping.erase(NMit++);

     } while(!done);
    

  }

  void
  relayData(const Data& data, std::multimap<std::string, ID_Name>::iterator it){
    std::cout << "RelayData...\n";
    std::string ciphertext = it->second.second;
    Block b = data.getContent();
    std::string plainData((char*)b.value(),b.value_size());
    std::string cipherHolder;

    byte key[AES_STANDARD];
    byte iv[AES_STANDARD];
    memset(key,0x00,AES_STANDARD);
    memset(iv,0x00,AES_STANDARD);
    
    RAND_bytes(key,sizeof(key)-1);
    RAND_bytes(iv,sizeof(iv)-1);

    // Encrypt data
    std::string content = AES_Enc(key, iv, plainData, cipherHolder);
    
    Name cipherName(ciphertext);
    std::cout << "Sending data with name:  " << cipherName.toUri() << std::endl;
    shared_ptr<Data> data2 = make_shared<Data>();
    data2->setName(cipherName);
    data2->setFreshnessPeriod(10_s);
    data2->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());
    m_keyChain.sign(*data2);
    m_face.put(*data2);
   
  }

  void
  onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;
  }

  void
  onTimeout(const Interest& interest)
  {
    std::cout << "Timeout " << interest << std::endl;
  } 

private:
  Face m_face;
  KeyChain m_keyChain;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  ndn::examples::Producer producer;
  try {
    producer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
