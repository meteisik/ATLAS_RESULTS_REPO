import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_RuneComet {

    public void runRuneComet() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("RUNE_COMET_FILTER");
            break;
        default:
            data = null;
            break;
        }
        (new CWE89_P06_V2_RuneCometSink()).queryRuneComet(data);
    }
}

class CWE89_P06_V2_RuneCometSink {
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
