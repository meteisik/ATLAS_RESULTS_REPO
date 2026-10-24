import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_SaffronPrismSafe {

    public void runSaffronPrism() throws XPathExpressionException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_SaffronPrismSafeSink()).sinkSaffronPrism(dataArray);
    }
}

class CWE643_P08_V2_SaffronPrismSafeSink {

    public void sinkSaffronPrism(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
