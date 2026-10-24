import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_IvoryCometSafe {

    private String loadIvoryComet() {
        String data;
        data = "foo";
        return data;
    }

    public void runIvoryComet() throws SQLException {
        String data = loadIvoryComet();
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
}
