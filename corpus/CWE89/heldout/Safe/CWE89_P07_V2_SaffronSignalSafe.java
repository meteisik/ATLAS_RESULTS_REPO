import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SaffronSignalSafe {

    public void runSaffronSignal() throws SQLException {
        String data;
        if (true) {
            data = (new CWE89_P07_V2_SaffronSignalSafeSource()).loadSaffronSignal();
        } else {
            data = null;
        }
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        Statement saffronSignalStatement = null;
        ResultSet saffronSignalRows = null;
        try {
            saffronSignalStatement = saffronSignalConnection.createStatement();
            saffronSignalRows = saffronSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronSignalRows.getRow());
        } finally {
            if (saffronSignalRows != null) {
                saffronSignalRows.close();
            }
            if (saffronSignalStatement != null) {
                saffronSignalStatement.close();
            }
            saffronSignalConnection.close();
        }
    }
}

class CWE89_P07_V2_SaffronSignalSafeSource {
    public String loadSaffronSignal() {
        String data;
        data = "foo";
        return data;
    }
}
