import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_VelvetMantis {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void runVelvetMantis() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("VELVET_MANTIS_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_VelvetMantisSink()).sinkVelvetMantis(dataContainer);
    }
}

class CWE643_P09_V2_VelvetMantisSink {

    public void sinkVelvetMantis(CWE643_P09_V2_VelvetMantis.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
