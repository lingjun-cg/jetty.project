# DO NOT EDIT - See: https://www.eclipse.org/jetty/documentation/current/startup-modules.html

[description]
Adds servlet standard security handling to the classpath.

[environment]
ee8

[depend]
server
ee8-servlet

[lib]
lib/jetty-security-${jetty.version}.jar
lib/jetty-ee8-security-${jetty.version}.jar
