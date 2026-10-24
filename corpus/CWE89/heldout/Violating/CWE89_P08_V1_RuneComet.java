import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_RuneComet {

    public void runRuneComet() throws SQLException {
        String data;
        data = System.getenv("RUNE_COMET_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_RuneCometSink()).queryRuneComet(dataArray);
    }
}

class CWE89_P08_V1_RuneCometSink {
    public void queryRuneComet(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
