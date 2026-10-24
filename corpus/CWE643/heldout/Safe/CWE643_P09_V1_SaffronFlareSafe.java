import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SaffronFlareSafe {

    static class Container {
        public String containerOne;
    }

    public void runSaffronFlare() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SaffronFlareSafeSink()).sinkSaffronFlare(dataContainer);
    }
}

class CWE643_P09_V1_SaffronFlareSafeSink {

    public void sinkSaffronFlare(CWE643_P09_V1_SaffronFlareSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String saffronFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronFlareTokens = data.split("||");
            if (saffronFlareTokens.length < 2) {
                return;
            }
            String saffronFlareUser = saffronFlareTokens[0];
            String saffronFlarePass = saffronFlareTokens[1];
            XPath saffronFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronFlareXml = new InputSource(saffronFlareXmlFile);
            String saffronFlareQuery = "//users/user[name/text()='" + saffronFlareUser
                    + "' and pass/text()='" + saffronFlarePass + "']" + "/secret/text()";
            String saffronFlareSecret = (String) saffronFlareXPath.evaluate(saffronFlareQuery, saffronFlareXml, XPathConstants.STRING);
            System.out.println(saffronFlareSecret);
        }
    }
}
