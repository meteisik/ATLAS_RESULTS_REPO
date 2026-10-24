import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetSundial {

    public static String data;

    public void runVelvetSundial() throws XPathExpressionException {
        data = System.getenv("VELVET_SUNDIAL_ADD");
        (new CWE643_P10_V1_VelvetSundialSink()).sinkVelvetSundial();
    }
}

class CWE643_P10_V1_VelvetSundialSink {

    public void sinkVelvetSundial() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetSundial.data;
        String velvetSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetSundialTokens = data.split("||");
            if (velvetSundialTokens.length < 2) {
                return;
            }
            String velvetSundialUser = velvetSundialTokens[0];
            String velvetSundialPass = velvetSundialTokens[1];
            XPath velvetSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetSundialXml = new InputSource(velvetSundialXmlFile);
            String velvetSundialQuery = "//users/user[name/text()='" + velvetSundialUser
                    + "' and pass/text()='" + velvetSundialPass + "']" + "/secret/text()";
            String velvetSundialSecret = (String) velvetSundialXPath.evaluate(velvetSundialQuery, velvetSundialXml, XPathConstants.STRING);
            System.out.println(velvetSundialSecret);
        }
    }
}
