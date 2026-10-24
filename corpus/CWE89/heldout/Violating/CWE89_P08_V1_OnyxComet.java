import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_OnyxComet {

    public void runOnyxComet() throws SQLException {
        String data;
        data = System.getenv("ONYX_COMET_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_OnyxCometSink()).queryOnyxComet(dataArray);
    }
}

class CWE89_P08_V1_OnyxCometSink {
    public void queryOnyxComet(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
