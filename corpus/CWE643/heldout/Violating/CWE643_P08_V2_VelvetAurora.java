import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_VelvetAurora {

    public void runVelvetAurora() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("VELVET_AURORA_ADD");
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_VelvetAuroraSink()).sinkVelvetAurora(dataArray);
    }
}

class CWE643_P08_V2_VelvetAuroraSink {

    public void sinkVelvetAurora(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String velvetAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetAuroraTokens = data.split("||");
            if (velvetAuroraTokens.length < 2) {
                return;
            }
            String velvetAuroraUser = velvetAuroraTokens[0];
            String velvetAuroraPass = velvetAuroraTokens[1];
            XPath velvetAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetAuroraXml = new InputSource(velvetAuroraXmlFile);
            String velvetAuroraQuery = "//users/user[name/text()='" + velvetAuroraUser
                    + "' and pass/text()='" + velvetAuroraPass + "']" + "/secret/text()";
            String velvetAuroraSecret = (String) velvetAuroraXPath.evaluate(velvetAuroraQuery, velvetAuroraXml, XPathConstants.STRING);
            System.out.println(velvetAuroraSecret);
        }
    }
}
