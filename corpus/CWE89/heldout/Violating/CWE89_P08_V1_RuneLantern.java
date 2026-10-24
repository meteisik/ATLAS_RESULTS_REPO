import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_RuneLantern {

    public void runRuneLantern() throws SQLException {
        String data;
        data = System.getenv("RUNE_LANTERN_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_RuneLanternSink()).queryRuneLantern(dataArray);
    }
}

class CWE89_P08_V1_RuneLanternSink {
    public void queryRuneLantern(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection runeLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLantern");
        Statement runeLanternStatement = null;
        ResultSet runeLanternRows = null;
        try {
            runeLanternStatement = runeLanternConnection.createStatement();
            runeLanternRows = runeLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeLanternRows.getRow());
        } finally {
            if (runeLanternRows != null) {
                runeLanternRows.close();
            }
            if (runeLanternStatement != null) {
                runeLanternStatement.close();
            }
            runeLanternConnection.close();
        }
    }
}
