import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SaffronSundialSafe {

    public void runSaffronSundial() throws SQLException {
        String data;
        if (5 == 5) {
            data = (new CWE89_P07_V2_SaffronSundialSafeSource()).loadSaffronSundial();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_SaffronSundialSafeSource {
    public String loadSaffronSundial() {
        String data;
        data = "foo";
        return data;
    }
}
