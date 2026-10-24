import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_AmberMantisSafe {

    static class Container {
        public String containerOne;
    }

    public void runAmberMantis() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_AmberMantisSafeSink()).sinkAmberMantis(dataContainer);
    }
}

class CWE643_P09_V2_AmberMantisSafeSink {

    public void sinkAmberMantis(CWE643_P09_V2_AmberMantisSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String amberMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberMantisTokens = data.split("||");
            if (amberMantisTokens.length < 2) {
                return;
            }
            String amberMantisUser = amberMantisTokens[0];
            String amberMantisPass = amberMantisTokens[1];
            XPath amberMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource amberMantisXml = new InputSource(amberMantisXmlFile);
            String amberMantisQuery = "//users/user[name/text()='" + amberMantisUser
                    + "' and pass/text()='" + amberMantisPass + "']" + "/secret/text()";
            String amberMantisSecret = (String) amberMantisXPath.evaluate(amberMantisQuery, amberMantisXml, XPathConstants.STRING);
            System.out.println(amberMantisSecret);
        }
    }
}
