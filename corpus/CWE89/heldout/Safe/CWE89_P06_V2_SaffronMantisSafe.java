import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SaffronMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronMantis() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SaffronMantisSafeSink()).querySaffronMantis(data);
    }
}

class CWE89_P06_V2_SaffronMantisSafeSink {
    public void querySaffronMantis(String data) throws SQLException {
        Connection saffronMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronMantis");
        Statement saffronMantisStatement = null;
        ResultSet saffronMantisRows = null;
        try {
            saffronMantisStatement = saffronMantisConnection.createStatement();
            saffronMantisRows = saffronMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronMantisRows.getRow());
        } finally {
            if (saffronMantisRows != null) {
                saffronMantisRows.close();
            }
            if (saffronMantisStatement != null) {
                saffronMantisStatement.close();
            }
            saffronMantisConnection.close();
        }
    }
}
