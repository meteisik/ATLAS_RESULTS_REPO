import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_RuneLanternSafe {

    public void runRuneLantern() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_RuneLanternSafeSink()).queryRuneLantern(data);
    }
}

class CWE89_P06_V2_RuneLanternSafeSink {
    public void queryRuneLantern(String data) throws SQLException {
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
