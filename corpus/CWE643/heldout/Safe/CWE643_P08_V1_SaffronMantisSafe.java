import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_SaffronMantisSafe {

    public void runSaffronMantis() throws XPathExpressionException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_SaffronMantisSafeSink()).sinkSaffronMantis(dataArray);
    }
}

class CWE643_P08_V1_SaffronMantisSafeSink {

    public void sinkSaffronMantis(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String saffronMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronMantisTokens = data.split("||");
            if (saffronMantisTokens.length < 2) {
                return;
            }
            String saffronMantisUser = saffronMantisTokens[0];
            String saffronMantisPass = saffronMantisTokens[1];
            XPath saffronMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronMantisXml = new InputSource(saffronMantisXmlFile);
            String saffronMantisQuery = "//users/user[name/text()='" + saffronMantisUser
                    + "' and pass/text()='" + saffronMantisPass + "']" + "/secret/text()";
            String saffronMantisSecret = (String) saffronMantisXPath.evaluate(saffronMantisQuery, saffronMantisXml, XPathConstants.STRING);
            System.out.println(saffronMantisSecret);
        }
    }
}
