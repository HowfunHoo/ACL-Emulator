package com.cs.haofan;

import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.reflect.Array;
import java.util.ArrayList;



public class Main {

    public static void main(String[] args) {


        ArrayList<String> acl = new ArrayList<String>();
        ArrayList<String> test = new ArrayList<String>();

        //read files
        try {
            String line = null;

            //open ACL.txt
            //When testing standard ACLs, the content in acl.txt and test.txt should all follow the format of the standard ACL.
            //When testing extended ACLs, the content in acl.txt and test.txt should all follow the format of the extended ACL.
            FileReader reader_acl = new FileReader("./ACL/extended_ACL.txt");
            //FileReader reader_acl = new FileReader("./ACL/standard_ACL.txt");

            BufferedReader br_acl = new BufferedReader(reader_acl);

            while ((line = br_acl.readLine()) != null) {
                acl.add(line);
            }

            br_acl.close();
            reader_acl.close();

            //open test.txt. Import the testing traffic
            FileReader reader_test = new FileReader("./test/test_extendedACL.txt");
            //FileReader reader_test = new FileReader("./test/test_standardACL.txt");

            BufferedReader br_test = new BufferedReader(reader_test);

            line = null;
            while ((line = br_test.readLine()) != null) {
                test.add(line);
            }

            br_test.close();
            reader_test.close();

        } catch (java.io.IOException e) {
            e.printStackTrace();
        }

        //Store the acl and test split by space and dot
        String[] acl_split = new String[22];
        String[] test_split = new String[9];

        //Some protocols. Classify the protocols written in lower letters into the protocols written in capital letters
        //The numbers behind the protocols are the port number of this protocol
        String[][] protocols = {{"TCP", "ftp", "20", "ssh", "22", "telnet", "23", "smtp", "25", "dns", "53", "http", "80"},
                                {"UDP", "snmp", "161"},
                                {"icmp"},
                                {"igmp"},
                                {"ip"}};

        //Port number of the packet
        String packet_port_num = "";

        //Indicate if the packet is listed on the ACL
        Boolean found;

        //Indicate whether the protocol of the packet is legal
        Boolean legal_protocol;

        //Start scanning the packets and compare them with ACL, checking if they are permitted
        for(String str_test : test){

            //Split the packet info. by space and dot
            test_split = str_test.split(" |\\.");

            //Execute only when the packet is extended format
            if (test_split.length > 4){
                //Initialize the legality of the packet
                legal_protocol = false;

                //Convert the protocol of the packet to the protocols written in ACLs
                loop:
                for (int x=0; x<protocols.length; x++){
                    for (int y=0; y<protocols[x].length; y++){
                        if (protocols[x][y].equalsIgnoreCase(test_split[8])){
                            test_split[8] = protocols[x][0];
                            packet_port_num = protocols[x][y+1];
                            legal_protocol = true;
                            break loop;
                        }
                    }
                }
                //If the protocol of the packet is not illegal, report error and skip this packet
                if (!legal_protocol){
                    System.out.println("ERROR: the protocol of the packet is illegal! Packet info: " + str_test);
                    continue;
                }
            }

            //Initialize the status that if the info. of the packet is found in the ACLs
            found = false;

            //Start scanning the ACLs and search of the ACL related to the packet
            for(String str_acl : acl){

                //Split the acl info. by space and dot
                acl_split = str_acl.split(" |\\.");

                //ignore the "interface" row and the "ip access-group" row
                if (acl_split[0].equalsIgnoreCase("access-list")){
                    int acl_num = 0;
                    if(acl_split[0].equals("access-list")){
                        acl_num = Integer.parseInt(acl_split[1]);
                    }

                    //Judge if the acl is standard acl or extended acl
                    if (acl_num>=1 && acl_num<=99){


                        if (acl_split.length > 4){
                            //Use Mask to match ip addr.
                            for(int i=7;i<11;i++){
                                if (acl_split[i].equals("255")) {
                                    acl_split[i-4]="0";
                                }
                            }

                            //When the mask of an ACL is 255.255.255.255
                            if (acl_split[7].equals("255") && acl_split[8].equals("255") && acl_split[9].equals("255")
                                    && acl_split[10].equals("255")){
                                found = true;
                                if (acl_split[2].equalsIgnoreCase("permit")){
                                    System.out.println(str_test+"  Permitted");
                                } else if (acl_split[2].equalsIgnoreCase("deny")){
                                    System.out.println(str_test+"  Denied");
                                }
                                break;
                            }

                        }

                        //When mask is 255.255.255.255 or ip addr. is any
                        if (acl_split[3].equalsIgnoreCase("any")){
                            found = true;
                            if (acl_split[2].equalsIgnoreCase("permit")){
                                System.out.println(str_test+"  Permitted");
                            } else if (acl_split[2].equalsIgnoreCase("deny")){
                                System.out.println(str_test+"  Denied");
                            }
                            break;
                        }

                        //Judge if this packet is permitted or denied
                        for (int i=3; i<7; i++){
                            if (acl_split[i].equals("0") || acl_split[i].equals(test_split[i-3])){
                                if (i==6){
                                    found = true;
                                    if (acl_split[2].equalsIgnoreCase("permit")){
                                        System.out.println(str_test+"  Permitted");
                                    } else if (acl_split[2].equalsIgnoreCase("deny")){
                                        System.out.println(str_test+"  Denied");
                                    }
                                    break;
                                }
                            }else {
                                break;
                            }
                        }


                    } else if(acl_num>=100 && acl_num<=199){
                        //Use Mask to match source ip addr.
                        for(int i=8;i<12;i++){
                            if (acl_split[i].equals("255")) {
                                acl_split[i-4]="0";
                            }
                        }
                        //Use Mask to match destination ip addr.
                        for(int i=16;i<20;i++){
                            if (acl_split[i].equals("255")) {
                                acl_split[i-4]="0";
                            }
                        }

                        //compare source ip addr.
                        loop:
                        for (int i=4; i<8; i++){
                            if (acl_split[i].equals("0") || acl_split[i].equals(test_split[i-4]) ||
                                    acl_split[4].equalsIgnoreCase("any")){

                                //When source ip addr. matched
                                if (i==7){

                                    //compare destination ip addr.
                                    for (int j=12; j<16; j++){
                                        if (acl_split[j].equals("0") || acl_split[j].equals(test_split[j-8]) ||
                                                acl_split[5].equalsIgnoreCase("any")){

                                            //When destination ip addr. matched
                                            if(j == 15){

                                                //compare protocols
                                                if ((acl_split[3].equalsIgnoreCase(test_split[8]) &&
                                                        acl_split[21].equals(packet_port_num)) ||
                                                        (acl_split[3].equalsIgnoreCase("IP"))){
                                                    found = true;
                                                    if (acl_split[2].equalsIgnoreCase("permit")){
                                                        System.out.println(str_test+"  Permitted");
                                                    } else if (acl_split[2].equalsIgnoreCase("deny")){
                                                        System.out.println(str_test+"  Denied");
                                                    }
                                                    break loop;
                                                }else {
                                                    break loop;
                                                }
                                            }
                                        } else {
                                            break loop;
                                        }

                                    }
                                }

                            }else {
                                break;
                            }
                        }


                    }

                }else {
                    continue;
                }

                //If the packet is found in the ACL, no need to scan the rest of ACL
                if (found){
                    break;
                }

            }

            //If the packet is not listed on the ACL, deny it
            if(!found){
                System.out.println(str_test+"  Denied");
            }


        }


    }
}
