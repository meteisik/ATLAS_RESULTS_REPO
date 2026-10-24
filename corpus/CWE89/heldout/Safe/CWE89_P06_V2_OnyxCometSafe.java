import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_OnyxCometSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runOnyxComet() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_OnyxCometSafeSink()).queryOnyxComet(data);
    }
}

class CWE89_P06_V2_OnyxCometSafeSink {
    public void queryOnyxComet(String data) throws SQLException {
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
