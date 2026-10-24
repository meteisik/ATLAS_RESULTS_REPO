import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_OnyxLotusSafe {
    private static boolean privateTrue = true;

    private String loadOnyxLotus() {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runOnyxLotus() throws SQLException {
        String data = loadOnyxLotus();
        Connection onyxLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLotus");
        Statement onyxLotusStatement = null;
        ResultSet onyxLotusRows = null;
        try {
            onyxLotusStatement = onyxLotusConnection.createStatement();
            onyxLotusRows = onyxLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxLotusRows.getRow());
        } finally {
            if (onyxLotusRows != null) {
                onyxLotusRows.close();
            }
            if (onyxLotusStatement != null) {
                onyxLotusStatement.close();
            }
            onyxLotusConnection.close();
        }
    }
}
