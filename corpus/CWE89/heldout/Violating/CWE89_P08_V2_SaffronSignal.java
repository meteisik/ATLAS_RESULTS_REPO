import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_SaffronSignal {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runSaffronSignal() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("SAFFRON_SIGNAL_FILTER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_SaffronSignalSink()).querySaffronSignal(dataArray);
    }
}

class CWE89_P08_V2_SaffronSignalSink {
    public void querySaffronSignal(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        Statement saffronSignalStatement = null;
        ResultSet saffronSignalRows = null;
        try {
            saffronSignalStatement = saffronSignalConnection.createStatement();
            saffronSignalRows = saffronSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronSignalRows.getRow());
        } finally {
            if (saffronSignalRows != null) {
                saffronSignalRows.close();
            }
            if (saffronSignalStatement != null) {
                saffronSignalStatement.close();
            }
            saffronSignalConnection.close();
        }
    }
}
