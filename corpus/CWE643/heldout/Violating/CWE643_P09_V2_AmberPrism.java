import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_AmberPrism {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void runAmberPrism() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_PRISM_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_AmberPrismSink()).sinkAmberPrism(dataContainer);
    }
}

class CWE643_P09_V2_AmberPrismSink {

    public void sinkAmberPrism(CWE643_P09_V2_AmberPrism.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String amberPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberPrismTokens = data.split("||");
            if (amberPrismTokens.length < 2) {
                return;
            }
            String amberPrismUser = amberPrismTokens[0];
            String amberPrismPass = amberPrismTokens[1];
            XPath amberPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource amberPrismXml = new InputSource(amberPrismXmlFile);
            String amberPrismQuery = "//users/user[name/text()='" + amberPrismUser
                    + "' and pass/text()='" + amberPrismPass + "']" + "/secret/text()";
            String amberPrismSecret = (String) amberPrismXPath.evaluate(amberPrismQuery, amberPrismXml, XPathConstants.STRING);
            System.out.println(amberPrismSecret);
        }
    }
}
