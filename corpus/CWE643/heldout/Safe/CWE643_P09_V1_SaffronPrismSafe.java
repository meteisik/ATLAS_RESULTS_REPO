import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SaffronPrismSafe {

    static class Container {
        public String containerOne;
    }

    public void runSaffronPrism() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SaffronPrismSafeSink()).sinkSaffronPrism(dataContainer);
    }
}

class CWE643_P09_V1_SaffronPrismSafeSink {

    public void sinkSaffronPrism(CWE643_P09_V1_SaffronPrismSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String saffronPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronPrismTokens = data.split("||");
            if (saffronPrismTokens.length < 2) {
                return;
            }
            String saffronPrismUser = saffronPrismTokens[0];
            String saffronPrismPass = saffronPrismTokens[1];
            XPath saffronPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronPrismXml = new InputSource(saffronPrismXmlFile);
            String saffronPrismQuery = "//users/user[name/text()='" + saffronPrismUser
                    + "' and pass/text()='" + saffronPrismPass + "']" + "/secret/text()";
            String saffronPrismSecret = (String) saffronPrismXPath.evaluate(saffronPrismQuery, saffronPrismXml, XPathConstants.STRING);
            System.out.println(saffronPrismSecret);
        }
    }
}
