import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_RuneCometSafe {

    public void runRuneComet() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_RuneCometSafeSource()).loadRuneComet();
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

class CWE89_P07_V1_RuneCometSafeSource {
    public String loadRuneComet() {
        String data;
        data = "foo";
        return data;
    }
}
