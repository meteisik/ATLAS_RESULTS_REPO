import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_RuneLotusSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runRuneLotus() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_RuneLotusSafeSink()).queryRuneLotus(data);
    }
}

class CWE89_P06_V2_RuneLotusSafeSink {
    public void queryRuneLotus(String data) throws SQLException {
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        Statement runeLotusStatement = null;
        ResultSet runeLotusRows = null;
        try {
            runeLotusStatement = runeLotusConnection.createStatement();
            runeLotusRows = runeLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeLotusRows.getRow());
        } finally {
            if (runeLotusRows != null) {
                runeLotusRows.close();
            }
            if (runeLotusStatement != null) {
                runeLotusStatement.close();
            }
            runeLotusConnection.close();
        }
    }
}
