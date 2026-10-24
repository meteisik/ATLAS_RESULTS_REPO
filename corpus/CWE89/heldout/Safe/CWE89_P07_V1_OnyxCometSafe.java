import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_OnyxCometSafe {

    public void runOnyxComet() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_OnyxCometSafeSource()).loadOnyxComet();
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
}

class CWE89_P07_V1_OnyxCometSafeSource {
    public String loadOnyxComet() {
        String data;
        data = "foo";
        return data;
    }
}
