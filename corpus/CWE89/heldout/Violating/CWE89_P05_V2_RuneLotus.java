import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_RuneLotus {

    private String runeLotusData;

    private void queryRuneLotus() throws SQLException {
        String data = runeLotusData;
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

    public void runRuneLotus() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("RUNE_LOTUS_FILTER");
        } else {
            data = null;
        }
        runeLotusData = data;
        queryRuneLotus();
    }
}
