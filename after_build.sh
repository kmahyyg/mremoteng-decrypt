#!/bin/sh

cd out/artifacts/decipher_mremoteng_jar
zip -d decipher_mremoteng.jar 'META-INF/.SF' 'META-INF/.RSA' 'META-INF/*SF'