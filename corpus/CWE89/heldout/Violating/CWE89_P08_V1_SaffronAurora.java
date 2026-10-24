import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_SaffronAurora {

    public void runSaffronAurora() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_AURORA_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_SaffronAuroraSink()).querySaffronAurora(dataArray);
    }
}

class CWE89_P08_V1_SaffronAuroraSink {
    public void querySaffronAurora(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        Statement saffronAuroraStatement = null;
        ResultSet saffronAuroraRows = null;
        try {
            saffronAuroraStatement = saffronAuroraConnection.createStatement();
            saffronAuroraRows = saffronAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronAuroraRows.getRow());
        } finally {
            if (saffronAuroraRows != null) {
                saffronAuroraRows.close();
            }
            if (saffronAuroraStatement != null) {
                saffronAuroraStatement.close();
            }
            saffronAuroraConnection.close();
        }
    }
}
