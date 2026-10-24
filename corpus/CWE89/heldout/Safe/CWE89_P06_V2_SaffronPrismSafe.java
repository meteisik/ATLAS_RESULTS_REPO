import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SaffronPrismSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronPrism() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SaffronPrismSafeSink()).querySaffronPrism(data);
    }
}

class CWE89_P06_V2_SaffronPrismSafeSink {
    public void querySaffronPrism(String data) throws SQLException {
        Connection saffronPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronPrism");
        Statement saffronPrismStatement = null;
        ResultSet saffronPrismRows = null;
        try {
            saffronPrismStatement = saffronPrismConnection.createStatement();
            saffronPrismRows = saffronPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronPrismRows.getRow());
        } finally {
            if (saffronPrismRows != null) {
                saffronPrismRows.close();
            }
            if (saffronPrismStatement != null) {
                saffronPrismStatement.close();
            }
            saffronPrismConnection.close();
        }
    }
}
