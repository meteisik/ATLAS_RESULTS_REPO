import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_RuneLantern {
    private static boolean privateTrue = true;

    public void runRuneLantern() throws SQLException {
        String data;
        if (privateTrue) {
            data = (new CWE89_P07_V2_RuneLanternSource()).loadRuneLantern();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_RuneLanternSource {
    public String loadRuneLantern() {
        String data;
        data = System.getenv("RUNE_LANTERN_FILTER");
        return data;
    }
}
