# HTTP Methods Discloser

This extension makes a `OPTIONS` request and 
determines if other HTTP methods than the original request are available.

If there are other methods available, the request under `Proxy/Http History` will be highlighted and other available HTTP
methods will be set in `Comment` column.



# Installation
1. `mvn clean package`
2. In Burp, go to Extender => Extensions.
3. Select `Add`. Select the JAR file and finish the wizard.
