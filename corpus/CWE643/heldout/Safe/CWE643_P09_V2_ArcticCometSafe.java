import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_ArcticCometSafe {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void runArcticComet() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_ArcticCometSafeSink()).sinkArcticComet(dataContainer);
    }
}

class CWE643_P09_V2_ArcticCometSafeSink {

    public void sinkArcticComet(CWE643_P09_V2_ArcticCometSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String arcticCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticCometTokens = data.split("||");
            if (arcticCometTokens.length < 2) {
                return;
            }
            String arcticCometUser = arcticCometTokens[0];
            String arcticCometPass = arcticCometTokens[1];
            XPath arcticCometXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticCometXml = new InputSource(arcticCometXmlFile);
            String arcticCometQuery = "//users/user[name/text()='" + arcticCometUser
                    + "' and pass/text()='" + arcticCometPass + "']" + "/secret/text()";
            String arcticCometSecret = (String) arcticCometXPath.evaluate(arcticCometQuery, arcticCometXml, XPathConstants.STRING);
            System.out.println(arcticCometSecret);
        }
    }
}
