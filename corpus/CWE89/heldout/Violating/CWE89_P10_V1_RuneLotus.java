import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_RuneLotus {

    public static String data;

    public void runRuneLotus() throws SQLException {
        data = System.getenv("RUNE_LOTUS_FILTER");
        (new CWE89_P10_V1_RuneLotusSink()).queryRuneLotus();
    }
}

class CWE89_P10_V1_RuneLotusSink {
    public void queryRuneLotus() throws SQLException {
        String data = CWE89_P10_V1_RuneLotus.data;
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
