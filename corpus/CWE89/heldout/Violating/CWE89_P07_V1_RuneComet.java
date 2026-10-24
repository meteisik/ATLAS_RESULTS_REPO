import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_RuneComet {

    public void runRuneComet() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_RuneCometSource()).loadRuneComet();
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

class CWE89_P07_V1_RuneCometSource {
    public String loadRuneComet() {
        String data;
        data = System.getenv("RUNE_COMET_FILTER");
        return data;
    }
}
