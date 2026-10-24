import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetCascade {

    public static String data;

    public void runVelvetCascade() throws XPathExpressionException {
        data = System.getenv("VELVET_CASCADE_ADD");
        (new CWE643_P10_V1_VelvetCascadeSink()).sinkVelvetCascade();
    }
}

class CWE643_P10_V1_VelvetCascadeSink {

    public void sinkVelvetCascade() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetCascade.data;
        String velvetCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetCascadeTokens = data.split("||");
            if (velvetCascadeTokens.length < 2) {
                return;
            }
            String velvetCascadeUser = velvetCascadeTokens[0];
            String velvetCascadePass = velvetCascadeTokens[1];
            XPath velvetCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetCascadeXml = new InputSource(velvetCascadeXmlFile);
            String velvetCascadeQuery = "//users/user[name/text()='" + velvetCascadeUser
                    + "' and pass/text()='" + velvetCascadePass + "']" + "/secret/text()";
            String velvetCascadeSecret = (String) velvetCascadeXPath.evaluate(velvetCascadeQuery, velvetCascadeXml, XPathConstants.STRING);
            System.out.println(velvetCascadeSecret);
        }
    }
}
