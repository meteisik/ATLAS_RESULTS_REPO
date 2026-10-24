import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SaffronAurora {

    static class Container {
        public String containerOne;
    }

    public void runSaffronAurora() throws XPathExpressionException {
        String data;
        data = System.getenv("SAFFRON_AURORA_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SaffronAuroraSink()).sinkSaffronAurora(dataContainer);
    }
}

class CWE643_P09_V1_SaffronAuroraSink {

    public void sinkSaffronAurora(CWE643_P09_V1_SaffronAurora.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String saffronAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronAuroraTokens = data.split("||");
            if (saffronAuroraTokens.length < 2) {
                return;
            }
            String saffronAuroraUser = saffronAuroraTokens[0];
            String saffronAuroraPass = saffronAuroraTokens[1];
            XPath saffronAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronAuroraXml = new InputSource(saffronAuroraXmlFile);
            String saffronAuroraQuery = "//users/user[name/text()='" + saffronAuroraUser
                    + "' and pass/text()='" + saffronAuroraPass + "']" + "/secret/text()";
            String saffronAuroraSecret = (String) saffronAuroraXPath.evaluate(saffronAuroraQuery, saffronAuroraXml, XPathConstants.STRING);
            System.out.println(saffronAuroraSecret);
        }
    }
}
