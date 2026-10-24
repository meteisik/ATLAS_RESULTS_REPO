import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_MosaicHelixSafe {

    public void runMosaicHelix() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = null;
            for (int j = 0; j < 1; j++) {
                data = "foo";
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String mosaicHelixXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                mosaicHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                mosaicHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] mosaicHelixTokens = data.split("||");
                if (mosaicHelixTokens.length < 2) {
                    return;
                }
                String mosaicHelixUser = mosaicHelixTokens[0];
                String mosaicHelixPass = mosaicHelixTokens[1];
                XPath mosaicHelixXPath = XPathFactory.newInstance().newXPath();
                InputSource mosaicHelixXml = new InputSource(mosaicHelixXmlFile);
                String mosaicHelixQuery = "//users/user[name/text()='" + mosaicHelixUser
                        + "' and pass/text()='" + mosaicHelixPass + "']" + "/secret/text()";
                String mosaicHelixSecret = (String) mosaicHelixXPath.evaluate(mosaicHelixQuery, mosaicHelixXml, XPathConstants.STRING);
                System.out.println(mosaicHelixSecret);
            }
        }
    }
}
