import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_VividSundial {

    static class Container {
        public String containerOne;
    }

    public void runVividSundial() throws XPathExpressionException {
        String data;
        if (true) {
            data = System.getenv("VIVID_SUNDIAL_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_VividSundialSink()).sinkVividSundial(dataContainer);
    }
}

class CWE643_P09_V2_VividSundialSink {

    public void sinkVividSundial(CWE643_P09_V2_VividSundial.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String vividSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividSundialTokens = data.split("||");
            if (vividSundialTokens.length < 2) {
                return;
            }
            String vividSundialUser = vividSundialTokens[0];
            String vividSundialPass = vividSundialTokens[1];
            XPath vividSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource vividSundialXml = new InputSource(vividSundialXmlFile);
            String vividSundialQuery = "//users/user[name/text()='" + vividSundialUser
                    + "' and pass/text()='" + vividSundialPass + "']" + "/secret/text()";
            String vividSundialSecret = (String) vividSundialXPath.evaluate(vividSundialQuery, vividSundialXml, XPathConstants.STRING);
            System.out.println(vividSundialSecret);
        }
    }
}
