import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronMantisSafe {

    public static String data;

    public void runSaffronMantis() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_SaffronMantisSafeSink()).querySaffronMantis();
    }
}

class CWE89_P10_V1_SaffronMantisSafeSink {
    public void querySaffronMantis() throws SQLException {
        String data = CWE89_P10_V1_SaffronMantisSafe.data;
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
