import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_JadeCascade {

    public void runJadeCascade() throws SQLException {
        String dataCopy;
        {
            String data;
            data = null;
            for (int j = 0; j < 1; j++) {
                data = System.getenv("JADE_CASCADE_FILTER");
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection jadeCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCascade");
            Statement jadeCascadeStatement = null;
            ResultSet jadeCascadeRows = null;
            try {
                jadeCascadeStatement = jadeCascadeConnection.createStatement();
                jadeCascadeRows = jadeCascadeStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(jadeCascadeRows.getRow());
            } finally {
                if (jadeCascadeRows != null) {
                    jadeCascadeRows.close();
                }
                if (jadeCascadeStatement != null) {
                    jadeCascadeStatement.close();
                }
                jadeCascadeConnection.close();
            }
        }
    }
}
