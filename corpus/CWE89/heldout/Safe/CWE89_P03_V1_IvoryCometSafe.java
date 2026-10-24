import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_IvoryCometSafe {

    private void queryIvoryComet(String data) throws SQLException {
        Connection ivoryCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryComet");
        Statement ivoryCometStatement = null;
        ResultSet ivoryCometRows = null;
        try {
            ivoryCometStatement = ivoryCometConnection.createStatement();
            ivoryCometRows = ivoryCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryCometRows.getRow());
        } finally {
            if (ivoryCometRows != null) {
                ivoryCometRows.close();
            }
            if (ivoryCometStatement != null) {
                ivoryCometStatement.close();
            }
            ivoryCometConnection.close();
        }
    }

    public void runIvoryComet() throws SQLException {
        String data;
        data = "foo";
        queryIvoryComet(data);
    }
}
