import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_AmberCascade {

    static class Container {
        public String containerOne;
    }

    public void runAmberCascade() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AMBER_CASCADE_ADD");
            break;
        default:
            data = null;
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_AmberCascadeSink()).sinkAmberCascade(dataContainer);
    }
}

class CWE643_P09_V2_AmberCascadeSink {

    public void sinkAmberCascade(CWE643_P09_V2_AmberCascade.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String amberCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberCascadeTokens = data.split("||");
            if (amberCascadeTokens.length < 2) {
                return;
            }
            String amberCascadeUser = amberCascadeTokens[0];
            String amberCascadePass = amberCascadeTokens[1];
            XPath amberCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource amberCascadeXml = new InputSource(amberCascadeXmlFile);
            String amberCascadeQuery = "//users/user[name/text()='" + amberCascadeUser
                    + "' and pass/text()='" + amberCascadePass + "']" + "/secret/text()";
            String amberCascadeSecret = (String) amberCascadeXPath.evaluate(amberCascadeQuery, amberCascadeXml, XPathConstants.STRING);
            System.out.println(amberCascadeSecret);
        }
    }
}
