import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_VelvetCascade {

    public void runVelvetCascade() throws XPathExpressionException {
        String data;
        if (true) {
            data = System.getenv("VELVET_CASCADE_ADD");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_VelvetCascadeSink()).sinkVelvetCascade(dataArray);
    }
}

class CWE643_P08_V2_VelvetCascadeSink {

    public void sinkVelvetCascade(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
