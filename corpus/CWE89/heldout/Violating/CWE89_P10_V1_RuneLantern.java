import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_RuneLantern {

    public static String data;

    public void runRuneLantern() throws SQLException {
        data = System.getenv("RUNE_LANTERN_FILTER");
        (new CWE89_P10_V1_RuneLanternSink()).queryRuneLantern();
    }
}

class CWE89_P10_V1_RuneLanternSink {
    public void queryRuneLantern() throws SQLException {
        String data = CWE89_P10_V1_RuneLantern.data;
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
