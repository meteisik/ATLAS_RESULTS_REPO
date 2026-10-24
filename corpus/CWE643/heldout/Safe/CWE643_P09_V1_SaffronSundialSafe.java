import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SaffronSundialSafe {

    static class Container {
        public String containerOne;
    }

    public void runSaffronSundial() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SaffronSundialSafeSink()).sinkSaffronSundial(dataContainer);
    }
}

class CWE643_P09_V1_SaffronSundialSafeSink {

    public void sinkSaffronSundial(CWE643_P09_V1_SaffronSundialSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String saffronSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronSundialTokens = data.split("||");
            if (saffronSundialTokens.length < 2) {
                return;
            }
            String saffronSundialUser = saffronSundialTokens[0];
            String saffronSundialPass = saffronSundialTokens[1];
            XPath saffronSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronSundialXml = new InputSource(saffronSundialXmlFile);
            String saffronSundialQuery = "//users/user[name/text()='" + saffronSundialUser
                    + "' and pass/text()='" + saffronSundialPass + "']" + "/secret/text()";
            String saffronSundialSecret = (String) saffronSundialXPath.evaluate(saffronSundialQuery, saffronSundialXml, XPathConstants.STRING);
            System.out.println(saffronSundialSecret);
        }
    }
}
