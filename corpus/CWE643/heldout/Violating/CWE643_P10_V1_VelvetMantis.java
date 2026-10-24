import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetMantis {

    public static String data;

    public void runVelvetMantis() throws XPathExpressionException {
        data = System.getenv("VELVET_MANTIS_ADD");
        (new CWE643_P10_V1_VelvetMantisSink()).sinkVelvetMantis();
    }
}

class CWE643_P10_V1_VelvetMantisSink {

    public void sinkVelvetMantis() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetMantis.data;
        String velvetMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetMantisTokens = data.split("||");
            if (velvetMantisTokens.length < 2) {
                return;
            }
            String velvetMantisUser = velvetMantisTokens[0];
            String velvetMantisPass = velvetMantisTokens[1];
            XPath velvetMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetMantisXml = new InputSource(velvetMantisXmlFile);
            String velvetMantisQuery = "//users/user[name/text()='" + velvetMantisUser
                    + "' and pass/text()='" + velvetMantisPass + "']" + "/secret/text()";
            String velvetMantisSecret = (String) velvetMantisXPath.evaluate(velvetMantisQuery, velvetMantisXml, XPathConstants.STRING);
            System.out.println(velvetMantisSecret);
        }
    }
}
