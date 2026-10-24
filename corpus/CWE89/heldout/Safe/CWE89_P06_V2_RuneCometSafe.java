import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_RuneCometSafe {

    public void runRuneComet() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        (new CWE89_P06_V2_RuneCometSafeSink()).queryRuneComet(data);
    }
}

class CWE89_P06_V2_RuneCometSafeSink {
    public void queryRuneComet(String data) throws SQLException {
        Connection runeCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeComet");
        Statement runeCometStatement = null;
        ResultSet runeCometRows = null;
        try {
            runeCometStatement = runeCometConnection.createStatement();
            runeCometRows = runeCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeCometRows.getRow());
        } finally {
            if (runeCometRows != null) {
                runeCometRows.close();
            }
            if (runeCometStatement != null) {
                runeCometStatement.close();
            }
            runeCometConnection.close();
        }
    }
}
