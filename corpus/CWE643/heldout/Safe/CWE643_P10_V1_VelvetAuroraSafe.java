import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetAuroraSafe {

    public static String data;

    public void runVelvetAurora() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_VelvetAuroraSafeSink()).sinkVelvetAurora();
    }
}

class CWE643_P10_V1_VelvetAuroraSafeSink {

    public void sinkVelvetAurora() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetAuroraSafe.data;
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
