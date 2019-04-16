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
#include "AES_Code.hpp"
#include <iostream>
#include <openssl/rand.h>
#include <string>
int counter=1;

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces can be used to prevent/limit name conflicts
namespace examples {

class Consumer : noncopyable
{
public:
  void
  runApp()
  {
    // Create random IV each time we send an interest
    byte iv[AES_STANDARD];
    memset(iv, 0x00, AES_STANDARD);
    RAND_bytes(iv, sizeof(iv)-1);

    //Create name with consumer ID
    Name consID = "111";
    std::string cipherHolder;
    Name interest = "producer1/testApp/randomData"+to_string(counter);
    //std::cout << "name before encrypt " << interest.toUri() <<std::endl;
    //std::cout << "Using key: " << m_key <<std::endl;
    std::string encodedString = AES_Enc(m_key, iv, interest.toUri(), cipherHolder);
    Name::Component aes((uint8_t*)encodedString.data(), encodedString.size());
    Name fullName = "proxy";

    fullName.append(consID);
    fullName.append(aes);

    Interest request(fullName);
    request.setInterestLifetime(2_s);
    request.setMustBeFresh(true);
    request.setApplicationParameters(reinterpret_cast<uint8_t*>(iv),sizeof(iv));
    std::cout << "\n\n Sending interest >> " << request << std::endl;
    m_face.expressInterest(request,
                           bind(&Consumer::onData, this,  _1, _2),
                           bind(&Consumer::onNack, this, _1, _2),
                           bind(&Consumer::onTimeout, this, _1));
    m_face.processEvents();

  }


  void
  run()
  {
    Interest interest(Name("/proxy/registration/111"));
    interest.setInterestLifetime(2_s); // 2 seconds
    interest.setMustBeFresh(true);
    //std::string b = "sdfasdf";
    //interest.setApplicationParameters(reinterpret_cast<const uint8_t*>(b.data()), b.size());

    m_face.expressInterest(interest,
                           bind(&Consumer::onData, this,  _1, _2),
                           bind(&Consumer::onNack, this, _1, _2),
                           bind(&Consumer::onTimeout, this, _1));

    std::cout << "Sending " << interest << std::endl;

    // processEvents will block until the requested data received or timeout occurs
    m_face.processEvents();
  }

private:
  void
  onData(const Interest& interest, const Data& data)
  {
    if(interest.getName().toUri().find("registration") != std::string::npos){
    	std::cout << data << std::endl;
    	Block comp = data.getContent();
    	unsigned char * keys = const_cast<unsigned char*>(comp.value());  
    	for (int i =0; i < AES_STANDARD; i++){
		m_key[i] = (byte)keys[i];
    	}
    	//std::string plain = "KITTY";
    	//std::string cipher;

    	//byte iv[AES_STANDARD];
    	//memset(iv,0x00, AES_STANDARD);
    	//RAND_bytes(iv, sizeof(iv));
    	//std::string encodedString = AES_Enc(m_key, iv, plain, cipher);
    	//std::string unenc;
    	//std::string stuff = AES_Dec(m_key,iv,encodedString,unenc);
    	//std::cout << "DEC: " << stuff << std::endl;
    }
    else{
		std::cout << "\nReceived data: " <<data<<std::endl;
	}
    
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
  byte m_key[AES_STANDARD];
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  ndn::examples::Consumer consumer;
  try {
    consumer.run();
    std::cout << "Registration finished\n";
    for(int i = 0; i < 100; i++){
	consumer.runApp();
        counter++;
    }
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
