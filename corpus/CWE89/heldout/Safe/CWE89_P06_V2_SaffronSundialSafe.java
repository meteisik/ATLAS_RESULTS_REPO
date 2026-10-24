import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SaffronSundialSafe {

    public void runSaffronSundial() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE89_P06_V2_SaffronSundialSafeSink()).querySaffronSundial(data);
    }
}

class CWE89_P06_V2_SaffronSundialSafeSink {
    public void querySaffronSundial(String data) throws SQLException {
        Connection saffronSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSundial");
        Statement saffronSundialStatement = null;
        ResultSet saffronSundialRows = null;
        try {
            saffronSundialStatement = saffronSundialConnection.createStatement();
            saffronSundialRows = saffronSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronSundialRows.getRow());
        } finally {
            if (saffronSundialRows != null) {
                saffronSundialRows.close();
            }
            if (saffronSundialStatement != null) {
                saffronSundialStatement.close();
            }
            saffronSundialConnection.close();
        }
    }
}
