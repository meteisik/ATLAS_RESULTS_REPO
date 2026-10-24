import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_OnyxCometSafe {

    private String onyxCometData;

    private void queryOnyxComet() throws SQLException {
        String data = onyxCometData;
        Connection onyxCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxComet");
        Statement onyxCometStatement = null;
        ResultSet onyxCometRows = null;
        try {
            onyxCometStatement = onyxCometConnection.createStatement();
            onyxCometRows = onyxCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxCometRows.getRow());
        } finally {
            if (onyxCometRows != null) {
                onyxCometRows.close();
            }
            if (onyxCometStatement != null) {
                onyxCometStatement.close();
            }
            onyxCometConnection.close();
        }
    }

    public void runOnyxComet() throws SQLException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        onyxCometData = data;
        queryOnyxComet();
    }
}
