import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_RuneLotus {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runRuneLotus() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE89_P07_V2_RuneLotusSource()).loadRuneLotus();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_RuneLotusSource {
    public String loadRuneLotus() {
        String data;
        data = System.getenv("RUNE_LOTUS_FILTER");
        return data;
    }
}
